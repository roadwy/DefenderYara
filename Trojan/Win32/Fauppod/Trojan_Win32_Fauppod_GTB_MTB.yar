
rule Trojan_Win32_Fauppod_GTB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d0 31 d2 89 15 ?? ?? ?? ?? 01 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 18 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}