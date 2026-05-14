
rule Trojan_BAT_KillMBR_KK_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 ?? ?? ?? ?? ?? 20 ff 00 00 00 5f d2 9c 00 07 17 58 0b 07 20 6a 77 78 00 fe 04 0d 09 2d dd } //20
		$a_81_1 = {2f 6b 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 20 2f 66 } //10 /k reg delete HKCR /f
		$a_81_2 = {5c 5c 5c 5c 2e 5c 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //5 \\\\.\\PhysicalDrive0
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}