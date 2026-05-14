
rule Trojan_Win64_Rhadamanthys_NTK_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 70 61 79 6c 6f 61 64 5f 69 6e 69 74 } //1 _payload_init
		$a_03_1 = {0f b6 44 24 ?? 88 41 07 0f b6 44 24 08 88 41 ?? 0f b6 44 24 ?? 88 41 09 0f b6 44 24 } //1
		$a_03_2 = {45 31 c9 ff d3 48 89 c7 31 c9 ba ?? 00 00 00 45 31 c0 45 31 c9 ff d3 48 89 c3 48 85 ff 0f 95 c0 48 85 db 0f 95 c1 20 c1 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}