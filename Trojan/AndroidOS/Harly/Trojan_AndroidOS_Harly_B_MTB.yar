
rule Trojan_AndroidOS_Harly_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Harly.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {a8 00 00 90 08 9d 41 f9 81 f6 ff d0 82 f6 ff d0 83 f6 ff d0 13 c1 04 91 21 70 24 91 42 f0 15 91 63 f8 1b 91 e0 03 13 aa } //1
		$a_03_1 = {a8 00 00 d0 08 [0-04] f9 c1 f5 ff d0 c2 f5 ff d0 c3 f5 ff d0 13 c1 04 91 21 30 1f 91 42 70 32 91 63 1c 0f 91 e0 03 13 aa } //1
		$a_00_2 = {5f 55 6e 77 69 6e 64 5f 47 65 74 54 65 78 74 52 65 6c 42 61 73 65 } //1 _Unwind_GetTextRelBase
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}