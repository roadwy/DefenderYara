
rule Trojan_Win64_Lazy_AMMC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 74 6f 70 20 54 72 79 69 6e 67 20 54 6f 20 52 65 76 65 72 73 65 20 59 6f 75 20 4e 6f 20 4c 69 66 65 20 46 61 67 67 6f 74 21 } //Stop Trying To Reverse You No Life Faggot!  2
		$a_80_1 = {59 6f 75 20 61 72 65 20 72 75 6e 6e 69 6e 67 20 74 68 69 73 20 70 72 6f 67 72 61 6d 20 61 6c 72 65 61 64 79 } //You are running this program already  2
		$a_80_2 = {74 79 70 65 3d 63 68 65 63 6b 62 6c 61 63 6b 6c 69 73 74 } //type=checkblacklist  2
		$a_80_3 = {78 78 78 78 3f 78 78 78 78 3f 3f 3f 3f 78 78 78 } //xxxx?xxxx????xxx  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}