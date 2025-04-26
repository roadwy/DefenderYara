
rule Trojan_Win32_Gozi_PAB_MTB{
	meta:
		description = "Trojan:Win32/Gozi.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f0 01 29 81 ?? ?? ?? ?? 8b 86 ac 00 00 00 2b 86 d4 00 00 00 8b 0d ?? ?? ?? ?? 2d fb fb 1b 00 01 81 80 00 00 00 8b 8e b4 00 00 00 a1 ?? ?? ?? ?? 31 04 39 83 c7 04 8b 86 8c 00 00 00 33 46 6c 48 09 86 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}