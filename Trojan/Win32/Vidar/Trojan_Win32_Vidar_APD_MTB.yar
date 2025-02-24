
rule Trojan_Win32_Vidar_APD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.APD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d9 83 e1 03 8a 8c 0c b8 00 00 00 32 0c 18 0f be c1 89 f1 50 6a 01 e8 5e 78 00 00 43 39 dd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}