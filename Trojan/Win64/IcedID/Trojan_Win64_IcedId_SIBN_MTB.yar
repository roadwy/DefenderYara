
rule Trojan_Win64_IcedId_SIBN_MTB{
	meta:
		description = "Trojan:Win64/IcedId.SIBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8d 46 ff 48 8d 15 ?? ?? ?? ?? 31 f6 8a 0a 88 0f 80 07 ?? c0 27 ?? 8a 0f 88 0b 8a 4a 01 88 0f 80 07 ?? 8a 0f 08 0b 41 8a 0e 30 0b 41 fe 06 8a 0b 88 0c 30 41 39 f0 74 ?? 48 ff c6 48 83 c2 } //1
		$a_03_1 = {31 ed 89 ef c1 c7 ?? 0f be eb 01 fd 8a 1e 48 ff c6 84 db 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}