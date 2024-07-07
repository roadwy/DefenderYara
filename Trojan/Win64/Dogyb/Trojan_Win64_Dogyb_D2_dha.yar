
rule Trojan_Win64_Dogyb_D2_dha{
	meta:
		description = "Trojan:Win64/Dogyb.D2!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 53 68 61 72 65 64 49 6e 66 6f } //1 gSharedInfo
		$a_01_1 = {4e 74 55 73 65 72 44 65 66 53 65 74 54 65 78 74 } //1 NtUserDefSetText
		$a_01_2 = {23 00 33 00 32 00 37 00 37 00 32 00 } //1 #32772
		$a_01_3 = {65 78 70 6c 6f 69 74 20 73 75 63 63 65 73 73 21 0a } //1
		$a_01_4 = {65 78 70 6c 6f 69 74 20 66 61 69 6c 65 64 21 0a } //1 硥汰楯⁴慦汩摥ਡ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}