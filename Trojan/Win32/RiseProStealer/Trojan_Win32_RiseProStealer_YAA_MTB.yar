
rule Trojan_Win32_RiseProStealer_YAA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 8d 52 01 33 ce 69 f1 93 01 00 01 8a 4a ff 84 c9 } //3
		$a_03_1 = {8b ca 83 e1 0f b8 1d 8c 7c ee 83 f9 0f ba 40 bf fe f6 0f 43 cf c1 e1 02 e8 ?? ?? ?? ?? 8b 55 f0 24 0f 8d 4a 1d 32 c1 32 c3 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}