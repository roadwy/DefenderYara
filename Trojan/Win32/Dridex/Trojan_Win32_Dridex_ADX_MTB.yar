
rule Trojan_Win32_Dridex_ADX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 08 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {01 00 3c 8f 4e 70 5e 6a 40 22 37 5c 30 7e c8 20 10 bc ed b6 81 e4 14 ce 47 d6 d9 5b 47 71 46 6a f5 68 88 db 81 10 5e 6a 73 82 17 5c e4 7e b4 6c 90 bc 6c b6 b5 b0 34 6e 47 d6 d9 0f c8 52 46 6a } //03 00 
		$a_80_1 = {2d 2d 73 2d 2d 70 70 2d 2d 2d 2d } //--s--pp----  03 00 
		$a_80_2 = {47 73 70 2e 70 64 62 } //Gsp.pdb  01 00 
		$a_80_3 = {43 72 79 70 74 43 41 54 41 64 6d 69 6e 43 61 6c 63 48 61 73 68 46 72 6f 6d 46 69 6c 65 48 61 6e 64 6c 65 } //CryptCATAdminCalcHashFromFileHandle  01 00 
		$a_81_4 = {23 50 23 45 23 45 23 54 23 50 23 2e 23 58 23 } //00 00  #P#E#E#T#P#.#X#
	condition:
		any of ($a_*)
 
}