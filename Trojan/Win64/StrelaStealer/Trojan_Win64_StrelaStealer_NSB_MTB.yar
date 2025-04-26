
rule Trojan_Win64_StrelaStealer_NSB_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.NSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {40 6d 62 61 49 54 6d 6a 5d 5a 74 47 45 66 49 5b 45 45 64 74 67 68 7a 68 6a 6e 56 44 75 4e 74 45 5f 45 44 65 61 } //2 @mbaITmj]ZtGEfI[EEdtghzhjnVDuNtE_EDea
		$a_81_1 = {59 7a 5d 68 4a 56 61 6f 4b 49 5b 67 7d 41 6d 4f 65 7a 66 58 56 56 4b 7c 48 4f 65 61 59 56 5d 54 41 54 5c 45 59 40 } //1 Yz]hJVaoKI[g}AmOezfXVVK|HOeaYV]TAT\EY@
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_3 = {41 6b 5d 45 54 6d 46 48 47 58 68 4e 6d 46 64 6a } //1 Ak]ETmFHGXhNmFdj
		$a_81_4 = {66 6e 41 74 69 5b 74 5c 48 6d 61 76 } //1 fnAti[t\Hmav
		$a_81_5 = {79 59 6e 47 4e 78 65 4d 68 7b 66 67 6f 78 45 54 4a 7b 66 62 65 4a 74 7a 61 5c 59 63 63 78 4e 45 6d 78 6e 68 68 59 76 61 49 } //1 yYnGNxeMh{fgoxETJ{fbeJtza\YccxNEmxnhhYvaI
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}