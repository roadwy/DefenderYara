
rule Trojan_Win32_Potao_A{
	meta:
		description = "Trojan:Win32/Potao.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 6e 65 77 2f 74 61 73 6b 00 } //1 港睥琯獡k
		$a_00_1 = {63 6f 64 65 3d 00 } //1 潣敤=
		$a_01_2 = {46 7a 73 70 74 78 6c 7a 68 58 5f } //1 FzsptxlzhX_
		$a_01_3 = {48 8d bd 02 ff ff ff 8d b5 00 ff ff ff 89 45 08 33 d2 2b fb 8b c3 2b f3 8a 08 66 c7 44 07 ff 00 00 80 f9 0d 75 05 88 0c 06 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}