
rule Trojan_Win64_IcedID_EM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 3b d1 72 0e 8b c6 25 43 4a 00 00 48 31 83 28 01 00 00 83 c1 03 48 63 c1 48 3b c2 75 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 69 70 74 53 74 72 69 6e 67 5f 70 4c 6f 67 41 74 74 72 } //1 ScriptString_pLogAttr
		$a_01_1 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } //1 ijniuashdyguas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_EM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 6a 68 61 73 79 75 69 6a 6b 61 73 } //1 Bjhasyuijkas
		$a_01_1 = {42 6e 6d 72 38 34 51 65 79 } //1 Bnmr84Qey
		$a_01_2 = {43 53 45 4e 56 78 4a } //1 CSENVxJ
		$a_01_3 = {45 68 73 54 65 44 30 73 32 6c } //1 EhsTeD0s2l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_EM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 35 6a 68 68 34 57 71 } //1 X5jhh4Wq
		$a_01_1 = {65 66 35 71 54 71 } //1 ef5qTq
		$a_01_2 = {68 61 73 64 6e 75 68 61 73 } //1 hasdnuhas
		$a_01_3 = {6f 59 56 45 54 72 } //1 oYVETr
		$a_01_4 = {72 66 6f 45 71 48 43 4e } //1 rfoEqHCN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4f 34 44 54 36 6a 48 54 55 } //1 IO4DT6jHTU
		$a_01_1 = {4e 6f 36 4d 4c 39 6a 4f 49 } //1 No6ML9jOI
		$a_01_2 = {52 58 56 6c 30 36 58 71 73 } //1 RXVl06Xqs
		$a_01_3 = {66 50 33 57 36 35 72 79 } //1 fP3W65ry
		$a_01_4 = {68 61 73 64 6e 75 68 61 73 } //1 hasdnuhas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 49 76 61 6b 4c 78 61 37 } //1 UIvakLxa7
		$a_01_1 = {55 59 74 62 6b 41 6a 77 } //1 UYtbkAjw
		$a_01_2 = {55 63 53 74 79 68 53 } //1 UcStyhS
		$a_01_3 = {61 67 6a 68 73 61 68 6a 61 73 6b 73 64 } //1 agjhsahjasksd
		$a_01_4 = {68 51 36 4a 38 6d 69 49 46 } //1 hQ6J8miIF
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 44 24 38 4f c6 44 24 39 16 e9 44 01 00 00 80 44 24 30 60 c6 44 24 31 39 66 3b d2 74 3b 80 44 24 34 3c c6 44 24 35 12 3a e4 74 56 } //2
		$a_01_1 = {69 75 61 73 64 75 79 75 61 67 73 64 6a 61 73 61 73 73 } //1 iuasduyuagsdjasass
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_IcedID_EM_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 3b ed 74 1d b8 6c 00 00 00 66 89 44 24 64 66 3b d2 74 dc 48 89 54 24 10 48 89 4c 24 08 3a ff 74 dc 48 81 ec f8 00 00 00 48 c7 44 24 50 00 00 00 00 3a d2 74 1c b8 6c 00 00 00 66 89 44 24 62 3a ed 74 c1 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_IcedID_EM_MTB_9{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 66 3b f6 74 d4 83 c0 62 66 89 44 24 34 3a e4 74 00 b8 54 00 00 00 83 c0 0f eb cc 48 83 ec 68 } //3
		$a_01_1 = {66 75 61 64 73 79 67 75 61 73 67 64 75 68 61 69 73 75 64 6a 79 75 61 67 73 64 75 61 } //2 fuadsyguasgduhaisudjyuagsdua
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 3a db 74 4f 66 89 44 24 36 b8 3e 00 00 00 e9 c0 01 00 00 48 83 ec 68 48 c7 44 24 20 00 00 00 00 66 3b e4 74 00 } //3
		$a_01_1 = {62 69 61 79 75 73 64 6a 61 73 64 75 67 61 79 73 68 67 64 6a 61 6b 73 61 } //2 biayusdjasdugayshgdjaksa
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 5a 44 69 52 64 4c 49 67 6d 44 74 76 57 6e } //1 PZDiRdLIgmDtvWn
		$a_01_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
		$a_01_2 = {52 73 6e 67 6b 47 6d 4b 52 49 52 57 45 43 5a 73 70 6c 4d 79 6d } //1 RsngkGmKRIRWECZsplMym
		$a_01_3 = {53 63 58 6f 56 41 72 72 58 65 6a 43 48 } //1 ScXoVArrXejCH
		$a_01_4 = {58 64 75 47 48 4f 58 46 4c 59 4c } //1 XduGHOXFLYL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_EM_MTB_12{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 42 77 78 55 55 4b 59 46 4a 6a 68 48 65 65 } //1 hBwxUUKYFJjhHee
		$a_01_1 = {6a 4b 68 45 44 68 71 62 70 44 4e 69 4b 73 71 } //1 jKhEDhqbpDNiKsq
		$a_01_2 = {6a 77 4d 76 77 41 68 6d 78 6d 70 75 } //1 jwMvwAhmxmpu
		$a_01_3 = {73 56 55 50 65 65 76 44 7a 74 6a } //1 sVUPeevDztj
		$a_01_4 = {79 61 73 66 62 67 61 73 75 66 62 68 61 67 66 79 6a 61 66 61 73 } //1 yasfbgasufbhagfyjafas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}