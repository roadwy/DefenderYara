
rule Trojan_Win64_Lazy_NY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 0d 40 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 00 e0 0e 00 } //5
		$a_01_1 = {53 00 74 00 69 00 63 00 6b 00 79 00 4e 00 6f 00 74 00 65 00 73 00 } //1 StickyNotes
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}