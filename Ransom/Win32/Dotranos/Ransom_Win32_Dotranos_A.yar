
rule Ransom_Win32_Dotranos_A{
	meta:
		description = "Ransom:Win32/Dotranos.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 00 43 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 /C vssadmin delete shadows /all /quiet
		$a_01_1 = {26 62 69 74 63 6f 69 6e 41 64 64 72 65 73 73 3d } //1 &bitcoinAddress=
		$a_01_2 = {3c 2f 61 3e 3c 62 72 3e 3c 61 20 63 6c 61 73 73 3d 22 73 75 62 6d 69 74 22 68 72 65 66 3d 22 68 74 74 70 73 3a 2f 2f } //1 </a><br><a class="submit"href="https://
		$a_01_3 = {3c 74 69 74 6c 65 3e 59 6f 75 72 20 64 61 74 61 20 77 61 73 20 6c 6f 63 6b 65 64 21 3c 2f 74 69 74 6c 65 3e } //1 <title>Your data was locked!</title>
		$a_01_4 = {28 62 6f 6f 74 73 65 63 74 2e 62 61 6b 7c 69 63 6f 6e 63 61 63 68 65 2e 64 62 7c 6e 74 75 73 65 72 2e 64 61 74 7c 74 68 75 6d 62 73 2e 64 62 7c 61 63 74 69 76 61 74 69 6f 6e 73 74 6f 72 65 2e 64 61 74 7c 6d 69 63 72 6f 73 6f 66 74 29 } //1 (bootsect.bak|iconcache.db|ntuser.dat|thumbs.db|activationstore.dat|microsoft)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}