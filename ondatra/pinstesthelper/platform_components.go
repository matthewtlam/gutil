package pinstesthelper

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/pkg/errors"
)

// HardwareInfo contains hardware components related information.
type HardwareInfo struct {
	fans     []FanInfo
	fantrays []FanTrayInfo
	fpgas    []FPGAInfo
	ics      []IntegratedCircuitInfo
	pcie     []PcieInfo
	security []SecurityComponentInfo
	storage  []StorageDeviceInfo
	cpu      []TemperatureSensorInfo
	heatsink []TemperatureSensorInfo
	exhaust  []TemperatureSensorInfo
	inlet    []TemperatureSensorInfo
	dimm     []TemperatureSensorInfo
}

// Software Component APIs.

// SwitchNameRegex returns the regex for switch name.
func SwitchNameRegex() string {
	return "^(ju|df|mn)(\\d+).*\\.([a-z]{3})(\\d{2})\\.(net|prod).google.com$"
}

// ImageVersionRegex returns the regular expressions for the image version of the switch.
func ImageVersionRegex() []string {
	return []string{
		"^gpins_daily_(20\\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])_([0-1]?[0-9]|2[0-3])_RC(\\d{2})$",
		"^gpins_release_(20\\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])_([0-1]?[0-9]|2[0-3])_(prod|dev)_RC(\\d{2})$",
	}
}

// System APIs.

// SystemInfo consists of system related information.
type SystemInfo struct {
	rebootTime     time.Duration
	cpuInfo        []CPUInfo
	loggingInfo    LoggingInfo
	memInfo        MemoryInfo
	mountPointInfo []MountPointInfo
	ntpServerInfo  []NTPServerInfo
}

// LoggingInfo contains a remote server addresses to be used for logging.
type LoggingInfo struct {
	IPv4RemoteAddresses []string
	IPv6RemoteAddresses []string
}

// CPUInfo contains CPU-related information.
type CPUInfo struct {
	index           uint32
	maxAverageUsage uint8
}

// GetIndex returns the CPU index.
func (c CPUInfo) GetIndex() uint32 {
	return c.index
}

// GetMaxAverageUsage returns the maximum CPU average usage.
func (c CPUInfo) GetMaxAverageUsage() uint8 {
	return c.maxAverageUsage
}

// RebootTimeForDevice returns the maximum time that the device might take to reboot.
func RebootTimeForDevice(t *testing.T, d *ondatra.DUTDevice) (time.Duration, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.systemInfo.rebootTime, nil
}

// LoggingServerAddressesForDevice returns remote logging server address information for a platform.
func LoggingServerAddressesForDevice(t *testing.T, d *ondatra.DUTDevice) (LoggingInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return LoggingInfo{}, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.systemInfo.loggingInfo, nil
}

// CPUInfoForDevice returns CPU related information for a device.
func CPUInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]CPUInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.systemInfo.cpuInfo, nil
}

// MemoryInfo contains memory related information.
type MemoryInfo struct {
	physical                     uint64
	freeThreshold                uint64
	usedThreshold                uint64
	correctableEccErrorThreshold uint64
}

// GetPhysical returns the expected physical memory.
func (m MemoryInfo) GetPhysical() uint64 {
	return m.physical
}

// GetFreeThreshold returns the free memory threshold.
func (m MemoryInfo) GetFreeThreshold() uint64 {
	return m.freeThreshold
}

// GetUsedThreshold returns the used memory threshold.
func (m MemoryInfo) GetUsedThreshold() uint64 {
	return m.usedThreshold
}

// GetCorrectableEccErrorThreshold returns the correctable ECC error threshold.
func (m MemoryInfo) GetCorrectableEccErrorThreshold() uint64 {
	return m.correctableEccErrorThreshold
}

// MemoryInfoForDevice returns memory related information for a device.
func MemoryInfoForDevice(t *testing.T, d *ondatra.DUTDevice) (MemoryInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return MemoryInfo{}, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.systemInfo.memInfo, nil
}

// MountPointInfo returns mount points related information.
type MountPointInfo struct {
	name string
}

// GetName returns the name of the mount point.
func (m MountPointInfo) GetName() string {
	return m.name
}

// MountPointsInfoForDevice returns information about all "required"
// mount points for a device.
func MountPointsInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]MountPointInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.systemInfo.mountPointInfo, nil
}

// NTPServerInfo returns NTP server related information.
type NTPServerInfo struct {
	ipv4Address      []string
	ipv6Address      []string
	stratumThreshold uint8
}

// GetIPv4Address returns NTP server's IPv4 addresses.
func (n NTPServerInfo) GetIPv4Address() []string {
	return n.ipv4Address
}

// GetIPv6Address returns NTP server's IPv6 addresses.
func (n NTPServerInfo) GetIPv6Address() []string {
	return n.ipv6Address
}

// GetStratumThreshold returns the stratum threshold for the NTP server.
func (n NTPServerInfo) GetStratumThreshold() uint8 {
	return n.stratumThreshold
}

// NTPServerInfoForDevice returns NTP server related information for a device.
func NTPServerInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]NTPServerInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.systemInfo.ntpServerInfo, nil
}

// Integrated Circuit APIs.

// IntegratedCircuitInfo consists of integrated-circuit related information.
type IntegratedCircuitInfo struct {
	name                           string
	correctedParityErrorsThreshold uint64
}

// GetName returns the integrated-circuit name.
func (i IntegratedCircuitInfo) GetName() string {
	return i.name
}

// GetCorrectedParityErrorsThreshold returns the corrected-parity-error
// threshold for the integrated-circuit.
func (i IntegratedCircuitInfo) GetCorrectedParityErrorsThreshold() uint64 {
	return i.correctedParityErrorsThreshold
}

// ICInfoForDevice returns integrated-circuit related information for all
// integrated circuits present in a platform.
func ICInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]IntegratedCircuitInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.hardwareInfo.ics, nil
}

// FPGA APIs.

// FPGAInfo consists of FPGA related information.
type FPGAInfo struct {
	name                 string
	manufacturer         string
	description          string
	firmwareVersionRegex string
	resetCauseNum        int
}

// GetName returns the FPGA name.
func (f FPGAInfo) GetName() string {
	return f.name
}

// GetMfgName returns the FPGA manufacturer.
func (f FPGAInfo) GetMfgName() string {
	return f.manufacturer
}

// GetDescription returns the FPGA description.
func (f FPGAInfo) GetDescription() string {
	return f.description
}

// GetFirmwareVersionRegex returns the FPGA firmware version regex.
func (f FPGAInfo) GetFirmwareVersionRegex() string {
	return f.firmwareVersionRegex
}

// GetResetCauseNum returns the number of reset causes reported by the FPGA.
func (f FPGAInfo) GetResetCauseNum() int {
	return f.resetCauseNum
}

// FPGAInfoForDevice returns FPGA related information for all FPGAs present in a
// platform.
func FPGAInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]FPGAInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}
	return info.hardwareInfo.fpgas, nil
}

// Threshold32 consists of the minimum and maximum thresholds as a float32.
type Threshold32 struct {
	min float32
	max float32
}

// GetMin returns the minimum threshold for the power information.
func (p Threshold32) GetMin() float32 {
	return p.min
}

// GetMax returns the maximum threshold for the power information.
func (p Threshold32) GetMax() float32 {
	return p.max
}

// Threshold64 consists of the minimum and maximum thresholds as a float64.
type Threshold64 struct {
	min float64
	max float64
}

// GetMin returns the minimum threshold for the power information.
func (p Threshold64) GetMin() float64 {
	return p.min
}

// GetMax returns the maximum threshold for the power information.
func (p Threshold64) GetMax() float64 {
	return p.max
}

// TemperatureSensorType defines the type of temperature sensors.
type TemperatureSensorType int

// Type of temperature sensors.
const (
	CPUTempSensor TemperatureSensorType = iota
	HeatsinkTempSensor
	ExhaustTempSensor
	InletTempSensor
	DimmTempSensor
)

// TemperatureSensorInfo consists of temperature sensor related information.
type TemperatureSensorInfo struct {
	name           string
	location       string
	maxTemperature float64
}

// GetName returns the temperature sensor name.
func (t TemperatureSensorInfo) GetName() string {
	return t.name
}

// GetLocation returns the temperature sensor location.
func (t TemperatureSensorInfo) GetLocation() string {
	return t.location
}

// GetMaxTemperature returns the temperature threshold for the temperature sensor.
func (t TemperatureSensorInfo) GetMaxTemperature() float64 {
	return t.maxTemperature
}

// TemperatureSensorInfoForDevice returns information about all temperature sensors
// of the specified type.
func TemperatureSensorInfoForDevice(t *testing.T, d *ondatra.DUTDevice, s TemperatureSensorType) ([]TemperatureSensorInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}

	switch s {
	case CPUTempSensor:
		return info.hardwareInfo.cpu, nil
	case HeatsinkTempSensor:
		return info.hardwareInfo.heatsink, nil
	case ExhaustTempSensor:
		return info.hardwareInfo.exhaust, nil
	case InletTempSensor:
		return info.hardwareInfo.inlet, nil
	case DimmTempSensor:
		return info.hardwareInfo.dimm, nil
	}

	return nil, errors.Errorf("invalid sensor type: %v", s)
}

// SecurityComponentInfo consists of security component related information.
type SecurityComponentInfo struct {
	name string
}

// GetName returns the security component name.
func (s SecurityComponentInfo) GetName() string {
	return s.name
}

// SecurityInfoForDevice returns information about all security components.
func SecurityInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]SecurityComponentInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}

	return info.hardwareInfo.security, nil
}

// Threshold is any numeric type that is used as a lower or upper threshold.
type Threshold interface {
	float64 | uint64 | uint32
}

// Thresholds encapsulates a set of inclusive lower and upper thresholds.
type Thresholds[T Threshold] struct {
	hasLo bool
	lo    T
	hasHi bool
	hi    T
}

// IsValid checks if a value is in the thresholds.
func (t Thresholds[T]) IsValid(v T) bool {
	if t.hasLo && v < t.lo {
		return false
	}
	if t.hasHi && v > t.hi {
		return false
	}
	return true
}

// ThresholdsToString is a helper method to convert a set of thresholds to a readable string.
func (t Thresholds[T]) String() string {
	var sb strings.Builder
	if t.hasLo {
		sb.WriteString("lo:>=")
		sb.WriteString(fmt.Sprintf("%v", t.lo))
	} else {
		sb.WriteString("(no lo)")
	}
	sb.WriteString(" ")

	if t.hasHi {
		sb.WriteString("hi:<=")
		sb.WriteString(fmt.Sprintf("%v", t.hi))
	} else {
		sb.WriteString("(no hi)")
	}

	return sb.String()
}

// SmartDataInfo consists of storage device SMART data related information.
type SmartDataInfo struct {
	writeAmplificationFactorThresholds Thresholds[float64]
	rawReadErrorRateThresholds         Thresholds[float64]
	throughputPerformanceThresholds    Thresholds[float64]
	reallocatedSectorCountThresholds   Thresholds[uint64]
	powerOnSecondsThresholds           Thresholds[uint64]
	ssdLifeLeftThresholds              Thresholds[uint64]
	avgEraseCountThresholds            Thresholds[uint32]
	maxEraseCountThresholds            Thresholds[uint32]
}

// GetWriteAmplificationFactorThresholds returns the write amplification factor thresholds.
func (s SmartDataInfo) GetWriteAmplificationFactorThresholds() Thresholds[float64] {
	return s.writeAmplificationFactorThresholds
}

// GetRawReadErrorRateThresholds returns the raw read error rate thresholds.
func (s SmartDataInfo) GetRawReadErrorRateThresholds() Thresholds[float64] {
	return s.rawReadErrorRateThresholds
}

// GetThroughputPerformanceThresholds returns the throughput performance thresholds.
func (s SmartDataInfo) GetThroughputPerformanceThresholds() Thresholds[float64] {
	return s.throughputPerformanceThresholds
}

// GetReallocatedSectorCountThresholds returns the throughput performance thresholds.
func (s SmartDataInfo) GetReallocatedSectorCountThresholds() Thresholds[uint64] {
	return s.reallocatedSectorCountThresholds
}

// GetPowerOnSecondsThresholds returns the throughput performance thresholds.
func (s SmartDataInfo) GetPowerOnSecondsThresholds() Thresholds[uint64] {
	return s.powerOnSecondsThresholds
}

// GetSsdLifeLeftThresholds returns the SSD life left thresholds.
func (s SmartDataInfo) GetSsdLifeLeftThresholds() Thresholds[uint64] {
	return s.ssdLifeLeftThresholds
}

// GetAvgEraseCountThresholds returns the average erase count thresholds.
func (s SmartDataInfo) GetAvgEraseCountThresholds() Thresholds[uint32] {
	return s.avgEraseCountThresholds
}

// GetMaxEraseCountThresholds returns the average erase count thresholds.
func (s SmartDataInfo) GetMaxEraseCountThresholds() Thresholds[uint32] {
	return s.maxEraseCountThresholds
}

// StorageDeviceInfo consists of storage device related information.
type StorageDeviceInfo struct {
	name              string
	isRemovable       bool
	ioErrorsThreshold uint64
	smartDataInfo     SmartDataInfo
}

// GetName returns the storage device name.
func (s StorageDeviceInfo) GetName() string {
	return s.name
}

// GetIsRemovable returns whether the storage device is removable or not.
func (s StorageDeviceInfo) GetIsRemovable() bool {
	return s.isRemovable
}

// GetIoErrorsThreshold returns the threshold for storage device I/O errors.
func (s StorageDeviceInfo) GetIoErrorsThreshold() uint64 {
	return s.ioErrorsThreshold
}

// GetSmartDataInfo returns the SMART data info.
func (s StorageDeviceInfo) GetSmartDataInfo() SmartDataInfo {
	return s.smartDataInfo
}

// StorageDeviceInfoForDevice returns information about all storage devices.
func StorageDeviceInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]StorageDeviceInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}

	return info.hardwareInfo.storage, nil
}

// FanInfo consists of fan related information.
type FanInfo struct {
	name        string
	isRemovable bool
	parent      string
	location    string
	maxSpeed    uint32
}

// GetName returns the fan name.
func (f FanInfo) GetName() string {
	return f.name
}

// GetIsRemovable returns whether the fan is removable or not.
func (f FanInfo) GetIsRemovable() bool {
	return f.isRemovable
}

// GetLocation returns the location of the fan.
func (f FanInfo) GetLocation() string {
	return f.location
}

// GetMaxSpeed returns the maximum speed of the fan.
func (f FanInfo) GetMaxSpeed() uint32 {
	return f.maxSpeed
}

// GetParent returns the parent component of the fan.
func (f FanInfo) GetParent() string {
	return f.parent
}

// FanTrayInfo consists of fan tray related information.
type FanTrayInfo struct {
	name        string
	isRemovable bool
	parent      string
	location    string
}

// GetName returns the fan tray name.
func (f FanTrayInfo) GetName() string {
	return f.name
}

// GetIsRemovable returns whether the fan tray is removable or not.
func (f FanTrayInfo) GetIsRemovable() bool {
	return f.isRemovable
}

// GetParent returns the parent component of the fan tray.
func (f FanTrayInfo) GetParent() string {
	return f.parent
}

// GetLocation returns the location of the fan tray.
func (f FanTrayInfo) GetLocation() string {
	return f.location
}

// FanInfoForDevice returns information about all fans.
func FanInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]FanInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}

	return info.hardwareInfo.fans, nil
}

// FanTrayInfoForDevice returns information about all fan trays.
func FanTrayInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]FanTrayInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}

	return info.hardwareInfo.fantrays, nil
}

// PcieInfo consists of PCIe device related information.
type PcieInfo struct {
	name string
}

// GetName returns the PCIe device name.
func (p PcieInfo) GetName() string {
	return p.name
}

// PcieInfoForDevice returns information about all PCIe devices.
func PcieInfoForDevice(t *testing.T, d *ondatra.DUTDevice) ([]PcieInfo, error) {
	info, err := platformInfoForDevice(t, d)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch platform specific information")
	}

	return info.hardwareInfo.pcie, nil
}
