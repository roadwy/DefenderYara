
rule Trojan_Win32_Makoob_SAH_MTB{
	meta:
		description = "Trojan:Win32/Makoob.SAH!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 00 61 00 63 00 72 00 79 00 2e 00 69 00 6e 00 69 00 } //1 nacry.ini
		$a_01_1 = {72 00 67 00 65 00 72 00 72 00 69 00 67 00 2e 00 74 00 78 00 74 00 } //1 rgerrig.txt
		$a_01_2 = {5c 00 63 00 6f 00 63 00 61 00 69 00 6e 00 69 00 7a 00 65 00 } //1 \cocainize
		$a_01_3 = {6c 00 69 00 6e 00 69 00 65 00 6c 00 6e 00 67 00 64 00 65 00 2e 00 70 00 72 00 6f 00 } //1 linielngde.pro
		$a_01_4 = {53 00 6b 00 72 00 61 00 62 00 6e 00 73 00 65 00 73 00 70 00 69 00 6c 00 73 00 2e 00 74 00 78 00 74 00 } //1 Skrabnsespils.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}