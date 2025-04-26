
rule Trojan_Win64_XDRKillRustz_A_MTB{
	meta:
		description = "Trojan:Win64/XDRKillRustz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {72 75 73 74 2d 78 64 72 2d 6b 69 6c 6c 65 72 } //1 rust-xdr-killer
		$a_00_1 = {56 48 83 ec 20 4c 89 c0 48 89 ce 49 81 f9 ff ff ff 7f 41 b8 ff ff ff 7f 4d 0f 42 c1 48 8b 0a 48 89 c2 45 31 c9 ff 15 15 5b 04 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}