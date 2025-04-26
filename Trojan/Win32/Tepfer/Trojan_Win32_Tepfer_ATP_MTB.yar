
rule Trojan_Win32_Tepfer_ATP_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.ATP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 fc 56 5f 33 39 83 ef 01 89 3b ff 33 6a fc 5e ?? ?? 2b ce 2b de 5e 0f ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}