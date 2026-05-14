
rule Trojan_Win32_Amadey_AAM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f4 50 8d 85 e4 fb ff ff 50 ff d3 6a 00 8d 85 e4 fb ff ff 50 8d 85 ec fd ff ff 50 ff 15 ?? ?? ?? ?? 6a 06 8d 85 e4 fb ff ff 50 } //2
		$a_01_1 = {8d 45 f4 50 8d 85 d4 f7 ff ff 50 ff d3 6a 00 6a 06 6a 02 6a 00 6a 00 68 00 00 00 40 8d 85 d4 f7 ff ff 50 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}