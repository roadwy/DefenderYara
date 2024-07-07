
rule Ransom_Win64_Nokoyawa_AM_MTB{
	meta:
		description = "Ransom:Win64/Nokoyawa.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 75 73 65 72 5c 44 65 73 6b 74 6f 70 5c 6e 65 77 5c 6e 6f 6b 6f 5c 74 61 72 67 65 74 5c 72 65 6c 65 61 73 65 5c 64 65 70 73 5c 6e 6f 6b 6f 2e 70 64 62 } //1 C:\Users\user\Desktop\new\noko\target\release\deps\noko.pdb
		$a_01_1 = {52 55 53 54 5f 42 41 43 4b 54 52 41 43 45 3d 66 75 6c 6c } //1 RUST_BACKTRACE=full
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}