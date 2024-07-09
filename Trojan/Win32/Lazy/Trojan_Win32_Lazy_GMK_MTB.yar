
rule Trojan_Win32_Lazy_GMK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 10 8b 55 14 80 3a 00 74 ?? ?? ?? ?? ac 32 02 aa ?? ?? ?? 42 49 85 c9 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}