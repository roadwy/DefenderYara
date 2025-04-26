
rule Trojan_Win32_Midie_SIBH2_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBH2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 d2 85 db 74 ?? 8a 0c 3a [0-20] 80 f1 ?? [0-20] 88 04 3a 42 3b d3 72 ?? 6a 00 6a 00 57 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}