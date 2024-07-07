
rule Trojan_Win32_TrickBotCrypt_FI_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b d0 2b 15 90 01 04 03 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b d0 a1 90 01 04 0f af 05 90 01 04 2b d0 a1 90 01 04 0f af 05 90 01 04 2b d0 2b 15 90 01 04 8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 55 f4 90 00 } //1
		$a_81_1 = {7a 34 42 35 49 6b 23 78 58 34 49 28 67 62 66 72 3f 37 42 63 6b 76 79 37 46 69 54 46 33 63 37 3f 56 44 7a 46 29 53 5a 25 71 2b 6f 56 57 29 59 28 55 38 43 58 24 73 6d 55 21 25 24 44 57 67 65 77 47 70 36 61 57 64 38 70 59 64 56 } //1 z4B5Ik#xX4I(gbfr?7Bckvy7FiTF3c7?VDzF)SZ%q+oVW)Y(U8CX$smU!%$DWgewGp6aWd8pYdV
		$a_81_2 = {70 52 67 24 45 4d 26 25 42 31 35 50 51 30 2a 49 48 36 7a 4d 65 30 32 73 4c 5a 3c 46 64 2a 6a 3c 4f 37 62 43 73 72 25 47 72 25 6e 43 28 41 69 6c 3e 64 74 61 62 6d 76 79 55 34 65 4e 6d 6f 54 37 7a 64 34 4d 63 6f 6a 32 48 34 42 70 76 2a 75 69 54 63 31 51 73 51 70 75 6e 2b 35 26 6f 36 63 55 28 53 65 73 2b 70 5e 39 71 30 23 47 26 4e 61 } //1 pRg$EM&%B15PQ0*IH6zMe02sLZ<Fd*j<O7bCsr%Gr%nC(Ail>dtabmvyU4eNmoT7zd4Mcoj2H4Bpv*uiTc1QsQpun+5&o6cU(Ses+p^9q0#G&Na
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}