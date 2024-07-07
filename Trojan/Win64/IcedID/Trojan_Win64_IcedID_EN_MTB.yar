
rule Trojan_Win64_IcedID_EN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 6f 70 73 6a 79 68 75 6b } //1 topsjyhuk
		$a_01_1 = {10 00 00 00 10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_EN_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 61 69 6e 77 50 56 66 43 45 } //1 UainwPVfCE
		$a_01_1 = {56 49 4c 4f 4b 6e 49 70 76 4d 74 } //1 VILOKnIpvMt
		$a_01_2 = {56 62 68 6a 66 73 67 75 61 73 6a 66 6e 61 73 66 } //1 Vbhjfsguasjfnasf
		$a_01_3 = {58 76 6b 43 43 52 62 } //1 XvkCCRb
		$a_01_4 = {5a 42 50 41 63 5a } //1 ZBPAcZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EN_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 53 36 55 4d 46 34 73 4a 51 } //1 US6UMF4sJQ
		$a_01_1 = {56 70 65 72 46 67 37 4c 33 } //1 VperFg7L3
		$a_01_2 = {64 54 51 5a 6a 67 69 4b 6a } //1 dTQZjgiKj
		$a_01_3 = {66 79 77 54 61 77 76 78 45 41 } //1 fywTawvxEA
		$a_01_4 = {67 79 68 6a 75 68 79 61 73 62 68 6a 6b 61 73 } //1 gyhjuhyasbhjkas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EN_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 63 65 6a 73 6f } //1 mcejso
		$a_01_1 = {73 49 77 59 6a 67 4e 42 59 } //1 sIwYjgNBY
		$a_01_2 = {76 77 63 4b 70 42 5a 57 41 75 50 5a 74 6f 66 47 } //1 vwcKpBZWAuPZtofG
		$a_01_3 = {77 43 55 78 56 72 58 54 73 4d 47 56 78 42 47 72 } //1 wCUxVrXTsMGVxBGr
		$a_01_4 = {7a 75 62 69 74 6a 6b 66 6e 61 73 79 66 75 6a 61 73 6b } //1 zubitjkfnasyfujask
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EN_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 75 43 6a 39 68 32 39 56 57 61 6d 44 4d } //1 CuCj9h29VWamDM
		$a_01_1 = {4a 77 5a 6c 42 52 39 45 77 72 4e 6a 4f 4d } //1 JwZlBR9EwrNjOM
		$a_01_2 = {4b 72 4c 7a 59 45 51 7a 38 67 48 77 } //1 KrLzYEQz8gHw
		$a_01_3 = {52 51 73 6f 74 55 45 69 6b 39 57 72 59 4f 30 } //1 RQsotUEik9WrYO0
		$a_01_4 = {54 35 42 4d 64 73 54 31 57 75 } //1 T5BMdsT1Wu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}