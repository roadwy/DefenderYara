
rule Trojan_Win32_Emotet_RFA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {79 5f 66 76 41 32 66 75 56 23 71 68 5a 30 74 61 73 3e 69 40 3f 41 75 64 69 63 74 2a 78 6c 5f 47 28 47 77 57 25 58 4d 49 76 38 37 49 2b 3c 74 43 44 63 4b 4f 42 2a 76 73 6c } //1 y_fvA2fuV#qhZ0tas>i@?Audict*xl_G(GwW%XMIv87I+<tCDcKOB*vsl
		$a_81_1 = {61 5f 42 59 24 61 24 35 5e 30 69 6c 63 70 36 21 6b 48 67 42 53 58 51 4b 35 53 37 5f 25 56 62 29 61 43 6f 4f 39 5a 43 34 56 65 71 38 4e 68 45 4b 74 50 37 40 57 42 4f 4f 28 54 45 5a 54 3f 5e 6b 36 6c 62 5e 52 4c 42 51 75 29 21 41 54 29 46 6c 40 2a 54 47 61 24 68 2b 49 70 } //1 a_BY$a$5^0ilcp6!kHgBSXQK5S7_%Vb)aCoO9ZC4Veq8NhEKtP7@WBOO(TEZT?^k6lb^RLBQu)!AT)Fl@*TGa$h+Ip
		$a_03_2 = {88 14 08 e9 90 09 46 00 [0-20] 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d ?? 2b 0d ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45 } //5
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*5) >=6
 
}