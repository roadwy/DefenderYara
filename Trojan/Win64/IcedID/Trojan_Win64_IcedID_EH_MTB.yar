
rule Trojan_Win64_IcedID_EH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 74 79 61 73 75 66 61 73 6b 6c 66 6d 6a 6e 61 6b 73 } //1 ztyasufasklfmjnaks
		$a_03_1 = {f0 00 22 20 0b 02 90 01 02 00 78 05 00 00 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_EH_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 3a ff 74 00 48 89 54 24 10 48 89 4c 24 08 66 3b db 74 86 83 c0 24 66 89 44 24 54 3a f6 74 8b 33 c0 66 89 44 24 76 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_IcedID_EH_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 40 48 03 c8 90 02 03 74 90 00 } //3
		$a_01_1 = {8a 40 01 66 3b ed 74 00 88 44 24 21 8a 4c 24 20 e9 bf fc ff ff 88 44 24 20 48 8b 44 24 38 66 3b db 74 40 41 83 c0 0e } //4
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*4) >=7
 
}
rule Trojan_Win64_IcedID_EH_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 48 6e 67 44 6e 36 70 } //1 AHngDn6p
		$a_01_1 = {41 50 34 68 4e 73 52 6b 69 75 7a } //1 AP4hNsRkiuz
		$a_01_2 = {47 51 30 69 4f 6d 49 } //1 GQ0iOmI
		$a_01_3 = {4f 52 35 6e 5a 77 } //1 OR5nZw
		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //1 ijniuashdyguas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EH_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 67 6a 68 73 61 68 6a 61 73 6b 73 64 } //1 agjhsahjasksd
		$a_01_1 = {64 74 32 31 6d 70 61 } //1 dt21mpa
		$a_01_2 = {6b 77 62 4f 61 42 73 31 } //1 kwbOaBs1
		$a_01_3 = {71 43 7a 67 64 39 31 68 39 } //1 qCzgd91h9
		$a_01_4 = {75 41 66 53 62 53 6a 71 50 64 32 } //1 uAfSbSjqPd2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EH_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 30 51 49 71 4d 61 } //1 b0QIqMa
		$a_01_1 = {64 44 48 31 41 35 61 70 54 4c 41 } //1 dDH1A5apTLA
		$a_01_2 = {65 30 4c 70 4a 53 38 7a 64 } //1 e0LpJS8zd
		$a_01_3 = {68 4c 6c 6c 49 67 30 4d 4b 58 } //1 hLllIg0MKX
		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //1 ijniuashdyguas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EH_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 47 62 46 6d 73 44 75 6c } //1 WGbFmsDul
		$a_01_1 = {59 47 32 73 4a 75 51 75 59 56 } //1 YG2sJuQuYV
		$a_01_2 = {59 4f 4e 42 7a 64 34 6b 31 48 } //1 YONBzd4k1H
		$a_01_3 = {62 54 76 6a 5a 66 59 4e 53 36 50 } //1 bTvjZfYNS6P
		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //1 ijniuashdyguas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EH_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 68 41 67 44 6c 6f 75 4d 4b 59 } //1 ahAgDlouMKY
		$a_01_1 = {61 73 79 75 64 67 6e 61 73 64 79 61 68 64 62 79 75 61 6a 73 61 73 } //1 asyudgnasdyahdbyuajsas
		$a_01_2 = {6e 41 71 56 55 5a 42 79 52 55 6a 75 4c } //1 nAqVUZByRUjuL
		$a_01_3 = {74 6f 70 4b 70 69 52 7a 72 4c 74 6e 4d 6f 51 41 } //1 topKpiRzrLtnMoQA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_EH_MTB_9{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 70 73 64 62 69 65 77 5a 74 67 30 43 61 74 33 } //1 FpsdbiewZtg0Cat3
		$a_01_1 = {48 67 68 63 67 78 61 73 68 66 67 66 73 66 67 64 66 } //1 Hghcgxashfgfsfgdf
		$a_01_2 = {55 5a 6d 6c 59 4f 6f 55 79 30 63 4e 61 64 53 } //1 UZmlYOoUy0cNadS
		$a_01_3 = {56 66 7a 56 63 70 37 31 } //1 VfzVcp71
		$a_01_4 = {59 50 31 50 4f 4a 42 68 34 78 } //1 YP1POJBh4x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EH_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 69 61 73 67 79 66 61 62 68 73 66 79 61 73 6e 6a 61 75 73 61 73 } //1 uiasgyfabhsfyasnjausas
		$a_01_1 = {43 72 65 61 74 65 53 65 6d 61 70 68 6f 72 65 57 } //1 CreateSemaphoreW
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //1 WaitForSingleObjectEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_EH_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 61 73 74 66 64 61 73 75 64 68 79 75 67 61 77 75 6a 64 62 79 61 75 } //1 castfdasudhyugawujdbyau
		$a_01_1 = {52 65 6c 65 61 73 65 53 65 6d 61 70 68 6f 72 65 } //1 ReleaseSemaphore
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
		$a_01_3 = {74 00 65 00 72 00 65 00 73 00 76 00 65 00 34 00 6b 00 6e 00 61 00 } //1 teresve4kna
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_EH_MTB_12{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 31 04 0c 49 83 c4 90 01 01 8b 56 90 01 01 8b 8e 90 01 04 8b 86 90 01 04 03 ca 2b 86 90 01 04 83 f1 90 01 01 01 46 90 01 01 2b d1 8b 06 29 86 90 01 04 89 56 90 01 01 8b 06 8b 4e 90 01 01 33 8e 90 01 04 81 c1 90 01 04 0f af c1 89 06 8b 86 90 01 04 01 46 90 01 01 b8 90 01 04 2b 86 90 01 04 01 86 90 01 04 8b 46 90 01 01 2b 86 90 01 04 8b 4e 90 01 01 83 c0 90 01 01 31 86 90 01 04 2b 8e 90 01 04 8b 86 90 01 04 81 c1 90 01 04 0f af c1 89 86 90 01 04 49 81 fc 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}