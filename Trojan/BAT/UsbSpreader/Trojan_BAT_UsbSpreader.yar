
rule Trojan_BAT_UsbSpreader{
	meta:
		description = "Trojan:BAT/UsbSpreader,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 00 32 00 46 00 77 00 64 00 48 00 56 00 79 00 5a 00 51 00 3d 00 3d 00 } //1 Y2FwdHVyZQ==
		$a_01_1 = {53 00 47 00 46 00 75 00 5a 00 47 00 78 00 6c 00 54 00 47 00 6c 00 74 00 5a 00 56 00 56 00 54 00 51 00 69 00 35 00 49 00 59 00 57 00 35 00 6b 00 62 00 47 00 56 00 4d 00 61 00 57 00 31 00 6c 00 56 00 56 00 4e 00 43 00 } //1 SGFuZGxlTGltZVVTQi5IYW5kbGVMaW1lVVNC
		$a_01_2 = {64 00 47 00 39 00 79 00 63 00 6d 00 56 00 75 00 64 00 41 00 } //1 dG9ycmVudA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}