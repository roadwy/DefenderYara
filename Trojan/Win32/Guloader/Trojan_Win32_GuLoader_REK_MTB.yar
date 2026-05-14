
rule Trojan_Win32_GuLoader_REK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 63 70 68 6f 76 61 5c 62 75 6d 62 6c 65 66 6f 6f 74 5c 70 61 72 6d 6f 5c } //1 ecphova\bumblefoot\parmo\
		$a_81_1 = {5c 6c 69 6d 61 69 6c 5c 73 69 6d 70 65 6c 74 68 65 6e } //1 \limail\simpelthen
		$a_81_2 = {5c 70 6f 6b 65 77 65 65 64 5c 42 6c 69 73 73 5c 73 64 73 6b 69 66 74 65 2e 6c 6e 6b } //1 \pokeweed\Bliss\sdskifte.lnk
		$a_81_3 = {25 70 68 61 6c 6c 6f 72 72 68 61 67 69 61 25 5c 74 77 65 65 64 65 74 5c 61 6c 65 6b 73 61 6e 64 72 69 6e 73 6b 5c } //1 %phallorrhagia%\tweedet\aleksandrinsk\
		$a_81_4 = {5c 61 66 70 61 74 72 75 6c 6a 65 72 65 5c 75 6d 69 6e 64 65 6c 69 67 68 65 64 2e 69 6e 69 } //1 \afpatruljere\umindelighed.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}