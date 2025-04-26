
rule Trojan_Win64_StrelaStealer_DW_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 } //1 edom SOD ni nur eb tonnac margorp sihT
		$a_01_1 = {46 34 72 77 31 72 64 20 6a 35 6d 70 20 77 33 74 68 20 6e 34 20 6c 31 62 32 6c 20 64 32 66 33 6e 32 64 } //1 F4rw1rd j5mp w3th n4 l1b2l d2f3n2d
		$a_01_2 = {63 68 32 31 74 20 32 6e 67 33 6e 32 } //1 ch21t 2ng3n2
		$a_01_3 = {4e 65 77 21 21 21 20 63 68 32 31 74 2d 65 2d 63 6f 69 6e 73 21 20 4e 6f 77 20 79 6f 75 20 63 61 6e 20 62 75 79 20 63 68 32 31 74 2d 65 2d 63 6f 69 6e 73 20 74 6f 20 62 65 20 61 62 6c 65 20 74 6f 20 75 73 65 20 63 68 32 31 74 } //1 New!!! ch21t-e-coins! Now you can buy ch21t-e-coins to be able to use ch21t
		$a_01_4 = {63 68 32 31 74 32 6e 67 33 6e 32 34 36 5f 36 38 78 } //1 ch21t2ng3n246_68x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}