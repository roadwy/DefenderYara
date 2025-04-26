
rule Trojan_Win64_ClipBanker_AZ_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 4c 61 75 6e 63 68 5f 37 4b 4f 34 35 44 45 34 54 35 46 36 4f 4a 47 36 4e 46 4a 50 34 } //2 AutoLaunch_7KO45DE4T5F6OJG6NFJP4
		$a_01_1 = {5f 5a 4e 4b 53 74 37 5f 5f 63 78 78 31 31 31 32 62 61 73 69 63 5f 73 74 72 69 6e 67 49 63 53 74 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 53 61 49 63 45 45 36 6c 65 6e 67 74 68 45 76 } //1 _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv
		$a_01_2 = {5f 5a 4e 53 74 37 5f 5f 63 78 78 31 31 31 32 62 61 73 69 63 5f 73 74 72 69 6e 67 49 63 53 74 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 53 61 49 63 45 45 69 78 45 79 } //1 _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEy
		$a_01_3 = {5f 5a 4e 4b 53 74 37 5f 5f 63 78 78 31 31 31 32 62 61 73 69 63 5f 73 74 72 69 6e 67 49 63 53 74 31 31 63 68 61 72 5f 74 72 61 69 74 73 49 63 45 53 61 49 63 45 45 36 73 75 62 73 74 72 45 79 79 } //1 _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6substrEyy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}