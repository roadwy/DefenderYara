
rule Trojan_BAT_Lazy_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 34 39 38 33 31 37 36 35 2d 32 39 38 64 2d 34 33 66 32 2d 38 32 61 30 2d 30 31 38 63 33 62 66 66 37 38 35 37 } //2 $49831765-298d-43f2-82a0-018c3bff7857
		$a_01_1 = {67 64 5f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 gd_.Properties.Resources
		$a_01_2 = {5c 67 64 5d 2e 70 64 62 } //2 \gd].pdb
		$a_01_3 = {5c 6c 6f 6c 2e 70 64 62 } //2 \lol.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}