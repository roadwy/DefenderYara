
rule Trojan_Win32_Emotetcrypt_IV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {3c 42 47 73 73 4e 32 5e 61 64 6b 21 3e 3f 6a 67 48 2b 56 6e 64 21 3c 58 71 74 3e 44 6f 65 63 45 77 3f 4c 51 4d 63 47 67 73 5a 6f 79 41 44 4a 79 5a 6b 55 } //1 <BGssN2^adk!>?jgH+Vnd!<Xqt>DoecEw?LQMcGgsZoyADJyZkU
		$a_01_2 = {75 2b 4f 55 72 40 47 6e 77 37 57 55 38 77 76 7a 46 32 73 64 6e 21 73 63 73 62 26 57 4f 34 76 7a 75 47 41 73 2b 21 53 74 59 58 6a 21 62 79 37 6d 73 57 75 63 4b 2a 5f 4d 49 5f 6f 29 6d 28 } //1 u+OUr@Gnw7WU8wvzF2sdn!scsb&WO4vzuGAs+!StYXj!by7msWucK*_MI_o)m(
		$a_01_3 = {29 48 2b 21 43 42 64 65 45 4e 4d 32 54 56 4d 70 45 75 74 40 69 6d 21 45 63 65 36 47 39 2a 6a 4f 4a 40 68 2a 32 4c 39 43 42 78 29 4e 4b 40 56 } //1 )H+!CBdeENM2TVMpEut@im!Ece6G9*jOJ@h*2L9CBx)NK@V
		$a_01_4 = {6e 24 55 3c 51 33 71 69 30 4c 32 58 21 57 4c 21 62 6a 76 6c 4c 45 51 4b 5f 4a 44 4e 3c 51 29 68 4b 79 21 76 46 36 4d 61 7a 68 75 62 43 3e 73 4a 5a 40 3c 73 49 67 35 23 52 66 66 29 63 64 24 6a 46 68 53 55 5e 54 7a 40 56 28 66 6f 54 25 41 61 77 28 4c 69 49 74 7a 21 5f 6b 31 4a 65 33 48 4f 41 } //1 n$U<Q3qi0L2X!WL!bjvlLEQK_JDN<Q)hKy!vF6MazhubC>sJZ@<sIg5#Rff)cd$jFhSU^Tz@V(foT%Aaw(LiItz!_k1Je3HOA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}