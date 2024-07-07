
rule Trojan_BAT_CryptInject_NWN_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NWN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 bd a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 } //1
		$a_01_1 = {24 66 35 35 34 65 65 62 62 2d 36 35 62 64 2d 34 66 62 65 2d 61 39 31 32 2d 38 33 62 34 63 31 30 61 65 35 34 64 } //1 $f554eebb-65bd-4fbe-a912-83b4c10ae54d
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 2e 65 78 65 } //1 WindowsFormsApp3.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}