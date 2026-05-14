
rule Trojan_Win64_Mikey_SXF_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 7c 24 44 02 75 1d b9 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d 54 24 40 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75 dc } //20
		$a_80_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 61 74 6c 2e 69 6e 69 } //C:\Users\Public\Music\atl.ini  10
		$a_80_2 = {43 45 78 65 63 53 76 63 2e 65 78 65 } //CExecSvc.exe  2
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*2) >=32
 
}