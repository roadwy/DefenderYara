
rule Trojan_Win64_Lazy_GC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {67 6f 6f 64 2e 35 64 66 72 75 69 74 6a 6b 67 72 65 61 74 } //1 good.5dfruitjkgreat
		$a_01_1 = {43 77 6f 6e 2e 74 74 68 65 69 72 32 4b 61 62 75 6e 64 61 6e 74 6c 79 2e 6c 61 6e 64 } //1 Cwon.ttheir2Kabundantly.land
		$a_01_2 = {6f 3a 5c 64 69 72 5f 66 6f 72 5f 62 75 69 6c 64 73 5c 62 6c 64 4f 62 6a } //1 o:\dir_for_builds\bldObj
		$a_01_3 = {67 69 76 65 6e 65 76 65 72 79 6e } //1 giveneveryn
		$a_01_4 = {6b 74 72 65 65 6c 6d 61 6e 2c 52 6d } //1 ktreelman,Rm
		$a_01_5 = {73 61 79 69 6e 67 72 37 5a 73 68 65 2e 64 66 72 75 69 74 66 75 6c 64 7a 66 65 6d 61 6c 65 67 72 65 61 74 65 72 } //1 sayingr7Zshe.dfruitfuldzfemalegreater
		$a_01_6 = {36 6d 61 6c 65 79 6f 75 2e 72 65 2c 6d 75 6c 74 69 70 6c 79 2c 54 68 65 67 72 65 65 6e 72 65 70 6c 65 6e 69 73 68 66 69 74 73 65 6c 66 77 } //1 6maleyou.re,multiply,Thegreenreplenishfitselfw
		$a_01_7 = {76 67 30 35 62 33 77 45 2e 44 6c 6c } //1 vg05b3wE.Dll
		$a_01_8 = {73 45 4c 46 2e 65 58 65 } //1 sELF.eXe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}