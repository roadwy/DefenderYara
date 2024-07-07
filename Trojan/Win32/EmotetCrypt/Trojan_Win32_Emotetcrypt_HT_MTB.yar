
rule Trojan_Win32_Emotetcrypt_HT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_81_0 = {5e 2a 26 53 35 46 41 64 3c 37 50 3c 52 21 56 73 21 7a 24 63 6b 6f 75 3e 55 28 74 21 4f 64 5e 55 69 52 3e 77 4a 56 33 4a 37 41 76 5f 32 37 5f 26 68 43 36 5a 4d 59 53 72 6d 65 73 24 6e 30 33 6b 5a 44 62 71 4b 2a 51 5a 3e 43 40 5e 4e 4a 25 66 21 62 6a 24 6c 40 44 76 4a 2a 26 40 44 3c 33 21 } //1 ^*&S5FAd<7P<R!Vs!z$ckou>U(t!Od^UiR>wJV3J7Av_27_&hC6ZMYSrmes$n03kZDbqK*QZ>C@^NJ%f!bj$l@DvJ*&@D<3!
		$a_81_1 = {7a 41 3f 58 3c 73 52 30 4a 70 23 35 51 6a 58 3f 45 7a 6c 77 58 43 68 74 2a 74 42 31 26 3c 44 52 24 29 43 71 33 42 75 76 63 4e 41 69 39 4b 31 28 52 43 31 65 3f 58 54 63 24 5a 29 76 30 38 32 36 54 25 66 50 28 66 71 6e 64 74 70 6e 31 5f 44 77 52 32 46 78 4d 72 51 6a 63 68 4c 59 5f 79 28 40 21 26 47 6b 45 39 59 51 44 70 6e 54 } //1 zA?X<sR0Jp#5QjX?EzlwXCht*tB1&<DR$)Cq3BuvcNAi9K1(RC1e?XTc$Z)v0826T%fP(fqndtpn1_DwR2FxMrQjchLY_y(@!&GkE9YQDpnT
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}