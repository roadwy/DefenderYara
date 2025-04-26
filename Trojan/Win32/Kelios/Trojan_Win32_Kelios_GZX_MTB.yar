
rule Trojan_Win32_Kelios_GZX_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 40 9c 6c 1c b6 34 f6 bc ?? ?? ?? ?? 5c 70 ea 31 06 64 e5 a5 56 } //5
		$a_01_1 = {33 d4 66 2b d5 0f b7 d1 0f b6 16 66 a9 9a 2e 66 85 ce 8d b6 01 00 00 00 32 d3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}