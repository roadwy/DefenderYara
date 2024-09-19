
rule Trojan_Win32_Fauppod_GND_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 f2 88 d0 88 45 ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 45 ?? 83 c4 ?? 5e 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}