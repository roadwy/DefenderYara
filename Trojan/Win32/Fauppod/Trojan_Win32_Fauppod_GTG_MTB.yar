
rule Trojan_Win32_Fauppod_GTG_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 38 8d 05 ?? ?? ?? ?? 31 28 40 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? 31 18 8d 05 ?? ?? ?? ?? 50 c3 b9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}