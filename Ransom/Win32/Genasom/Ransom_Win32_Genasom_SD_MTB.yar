
rule Ransom_Win32_Genasom_SD_MTB{
	meta:
		description = "Ransom:Win32/Genasom.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 76 70 2e 65 78 65 } //01 00  avp.exe
		$a_81_1 = {5c 46 49 4c 45 53 2e 74 78 74 } //01 00  \FILES.txt
		$a_81_2 = {5c 5c 2e 5c 70 69 70 65 5c 74 75 72 75 6d } //01 00  \\.\pipe\turum
		$a_81_3 = {61 76 70 75 69 2e 65 78 65 } //01 00  avpui.exe
		$a_03_4 = {8b 45 08 3b 45 0c 7d 90 01 01 b9 01 00 00 00 6b d1 00 0f be 82 90 01 04 35 90 01 02 00 00 88 45 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}