
rule Trojan_Win32_Zenpak_DEH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 61 66 65 76 6f 72 61 67 69 74 61 6a 61 } //1 dafevoragitaja
		$a_81_1 = {6d 65 6e 61 6e 75 66 61 73 69 78 61 74 75 70 6f 66 65 6a 61 73 69 6e 75 78 61 77 69 66 75 63 61 } //1 menanufasixatupofejasinuxawifuca
		$a_81_2 = {7a 75 78 75 77 6f 7a 65 74 6f 7a 6f 66 75 70 61 6a 69 62 } //1 zuxuwozetozofupajib
		$a_81_3 = {62 61 67 75 72 6f 6b 75 74 69 66 65 63 61 66 75 77 65 76 69 72 6f 64 6f 73 61 78 61 76 75 63 20 25 73 20 25 64 20 25 66 } //1 bagurokutifecafuwevirodosaxavuc %s %d %f
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}