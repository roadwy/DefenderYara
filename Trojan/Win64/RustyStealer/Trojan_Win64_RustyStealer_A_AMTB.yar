
rule Trojan_Win64_RustyStealer_A_AMTB{
	meta:
		description = "Trojan:Win64/RustyStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 72 63 5c 6d 6f 64 75 6c 65 73 5c 70 65 72 73 69 73 74 2e 72 73 } //2 src\modules\persist.rs
		$a_81_1 = {73 72 63 5c 6d 6f 64 75 6c 65 73 5c 69 6e 74 65 72 66 61 63 65 2e 72 73 } //2 src\modules\interface.rs
		$a_81_2 = {73 72 63 5c 6d 6f 64 75 6c 65 73 5c 64 65 74 65 63 74 5f 61 76 2e 72 73 68 } //1 src\modules\detect_av.rsh
		$a_81_3 = {4e 6f 20 64 65 74 65 63 74 69 6f 6e 73 20 66 6f 75 6e 64 } //1 No detections found
		$a_81_4 = {73 74 61 62 6c 65 2d 78 38 36 5f 36 34 2d 70 63 2d 77 69 6e 64 6f 77 73 2d 6d 73 76 63 } //1 stable-x86_64-pc-windows-msvc
		$a_01_5 = {45 53 45 54 45 53 45 54 20 53 65 63 75 72 69 74 79 45 53 45 54 5c 45 53 45 54 20 53 65 63 75 72 69 74 79 45 53 45 54 5c 45 53 45 54 20 45 6e 64 70 6f 69 6e 74 20 53 65 63 75 72 69 74 79 } //1 ESETESET SecurityESET\ESET SecurityESET\ESET Endpoint Security
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}