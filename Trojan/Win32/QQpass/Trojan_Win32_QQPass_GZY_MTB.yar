
rule Trojan_Win32_QQPass_GZY_MTB{
	meta:
		description = "Trojan:Win32/QQPass.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 81 ed 10 00 00 00 81 ed ?? ?? ?? ?? e9 ?? ?? ?? ?? 03 df d1 6b b8 28 f6 a3 ?? ?? ?? ?? c0 4c 00 00 00 b9 a1 05 00 00 ba ?? ?? ?? ?? 30 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}