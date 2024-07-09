
rule PWS_BAT_Mintluks_A{
	meta:
		description = "PWS:BAT/Mintluks.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 69 63 72 6f 73 6f 66 74 20 63 6f 72 70 6f 72 61 74 69 6f 6e } //1 microsoft corporation
		$a_00_1 = {43 3a 5c 55 73 65 72 73 5c 73 61 5c 44 6f 77 6e 6c 6f 61 64 73 5c 55 6e 74 69 74 6c 65 64 5c 55 6e 74 69 74 6c 65 64 5c 56 42 2e 4e 45 54 } //2 C:\Users\sa\Downloads\Untitled\Untitled\VB.NET
		$a_00_2 = {49 6e 74 65 72 6e 65 74 5f 45 78 70 6c 6f 72 65 72 2e 70 64 62 } //1 Internet_Explorer.pdb
		$a_02_3 = {02 91 20 3f ff ff ff 5f 1f 18 62 0a 06 7e ?? ?? ?? ?? 02 17 58 91 1f 10 62 60 0a } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_02_3  & 1)*5) >=8
 
}