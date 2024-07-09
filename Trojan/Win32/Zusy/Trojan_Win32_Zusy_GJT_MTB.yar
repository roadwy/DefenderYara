
rule Trojan_Win32_Zusy_GJT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 38 81 c3 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 d0 75 ?? c3 68 68 ?? ?? ?? ?? 8d 3c 39 8b 3f 09 db } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}