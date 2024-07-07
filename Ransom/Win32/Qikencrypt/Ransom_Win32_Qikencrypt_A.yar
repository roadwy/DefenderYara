
rule Ransom_Win32_Qikencrypt_A{
	meta:
		description = "Ransom:Win32/Qikencrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {2a 2e 6f 64 74 2c 2a 2e 6f 64 73 2c 2a 2e 6f 64 70 2c 2a 2e 6f 64 62 2c 2a 2e } //1 *.odt,*.ods,*.odp,*.odb,*.
		$a_01_1 = {2a 2e 74 61 72 2c 2a 2e 65 6d 6c 2c 2a 2e 31 63 64 2c 2a } //1 *.tar,*.eml,*.1cd,*
		$a_01_2 = {2f 73 74 61 72 74 65 6e 63 2e 74 78 74 } //1 /startenc.txt
		$a_01_3 = {6c 73 74 2e 70 68 70 3f 73 74 72 3d } //1 lst.php?str=
		$a_01_4 = {2f 69 6e 64 65 78 2e 70 68 70 3f 69 64 73 3d } //1 /index.php?ids=
		$a_01_5 = {3c 2f 6b 65 79 3e } //1 </key>
		$a_01_6 = {63 68 69 63 6b 65 6e 6b 69 6c 6c 65 72 2e 63 6f 6d } //2 chickenkiller.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2) >=4
 
}