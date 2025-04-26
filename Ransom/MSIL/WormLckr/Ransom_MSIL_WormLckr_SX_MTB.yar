
rule Ransom_MSIL_WormLckr_SX_MTB{
	meta:
		description = "Ransom:MSIL/WormLckr.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 62 79 20 61 20 63 65 72 74 61 69 6e 20 74 69 6d 65 20 6f 72 20 74 75 72 6e 20 6f 66 66 20 74 68 65 } //1 If you do not pay by a certain time or turn off the
		$a_81_1 = {3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 61 6e 73 6f 6d 5f 76 6f 69 63 65 2e 76 62 73 } //1 :\Windows\System32\ransom_voice.vbs
		$a_81_2 = {5c 77 6f 72 6d 5f 74 6f 6f 6c 2e 73 79 73 } //1 \worm_tool.sys
		$a_81_3 = {57 6f 72 6d 4c 6f 63 6b 65 72 32 2e 30 } //1 WormLocker2.0
		$a_81_4 = {57 68 61 74 20 68 61 70 70 65 6e 73 20 69 66 20 49 20 64 6f 6e 27 74 20 70 61 79 } //1 What happens if I don't pay
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}