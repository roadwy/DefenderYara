
rule Trojan_Win32_Tnega_GP_MTB{
	meta:
		description = "Trojan:Win32/Tnega.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {d8 85 40 00 5b be ?? ?? ?? ?? 21 c6 e8 ?? ?? ?? ?? 50 58 31 1f 47 48 81 c6 ?? ?? ?? ?? 39 cf 75 de } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}