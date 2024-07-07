
rule Trojan_Win32_Emotetcrypt_HP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b ca 2b 0d 90 01 04 03 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 2b c8 8b 15 90 01 04 0f af 15 90 01 04 03 ca 2b 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 8b 45 f0 2b 05 90 01 04 2b 05 90 01 04 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 00 } //1
		$a_81_1 = {40 6e 71 33 28 30 6d 67 64 33 59 24 7a 78 5a 6e 56 5f 50 43 6f 6d 4a 58 6f 55 25 59 26 55 50 37 29 77 6f 6a 3c 4f 49 6a 61 4b 50 38 3e 52 49 37 70 61 67 48 5a 51 37 21 24 3e 47 64 50 63 5f 7a 5f 72 4a 79 76 21 5a 63 42 79 6f 47 7a 4d 53 44 6d 6b 4c 26 49 35 28 72 24 73 35 55 67 39 30 52 4d 48 49 4f } //1 @nq3(0mgd3Y$zxZnV_PComJXoU%Y&UP7)woj<OIjaKP8>RI7pagHZQ7!$>GdPc_z_rJyv!ZcByoGzMSDmkL&I5(r$s5Ug90RMHIO
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}