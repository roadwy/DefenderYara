
rule Trojan_Win32_Doina_SG_MTB{
	meta:
		description = "Trojan:Win32/Doina.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 61 75 78 64 61 74 61 2e 63 70 70 } //1 \auxdata.cpp
		$a_00_1 = {2f 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 2f 53 6f 6e 65 2f 25 73 } //1 /Program Files (x86)/Sone/%s
		$a_02_2 = {68 74 74 70 3a 2f 2f 31 35 39 2e 37 35 2e 32 33 37 2e 33 39 2f 68 2f [0-0f] 2e 68 74 6d 6c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}