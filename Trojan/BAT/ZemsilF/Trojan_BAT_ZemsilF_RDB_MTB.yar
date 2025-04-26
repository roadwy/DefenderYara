
rule Trojan_BAT_ZemsilF_RDB_MTB{
	meta:
		description = "Trojan:BAT/ZemsilF.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 35 36 33 39 66 35 30 2d 33 33 34 64 2d 34 61 37 37 2d 61 64 66 31 2d 62 61 65 38 33 37 33 34 31 30 65 61 } //1 35639f50-334d-4a77-adf1-bae8373410ea
		$a_01_1 = {52 75 6e 74 69 6d 65 20 42 72 6f 6b 65 72 } //1 Runtime Broker
		$a_01_2 = {43 68 72 6f 6d 65 43 72 61 73 68 48 61 6e 64 6c 65 72 } //1 ChromeCrashHandler
		$a_01_3 = {41 74 74 65 6e 64 61 6e 63 65 52 65 63 6f 72 64 65 72 } //1 AttendanceRecorder
		$a_01_4 = {4a 69 6f 6d 61 74 20 4c 4c 43 } //1 Jiomat LLC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}