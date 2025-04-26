
rule TrojanDropper_Win32_Dapato_GNX_MTB{
	meta:
		description = "TrojanDropper:Win32/Dapato.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {38 77 65 6b 79 62 33 64 38 62 62 77 65 } //8wekyb3d8bbwe  1
		$a_80_1 = {4b 47 34 32 33 34 42 37 31 79 4e 52 38 34 32 39 33 74 6f 72 6b 63 33 34 } //KG4234B71yNR84293torkc34  1
		$a_80_2 = {2f 70 75 62 6c 69 63 2f 70 61 67 65 73 2f 45 78 6f 64 75 73 2e 68 74 6d 6c } ///public/pages/Exodus.html  1
		$a_80_3 = {41 74 6f 6d 69 63 20 57 61 6c 6c 65 74 } //Atomic Wallet  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}