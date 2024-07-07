
rule Trojan_Win64_StrelaStealer_GPAD_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 45 f8 48 83 45 f8 08 eb 22 48 8b 45 f8 48 89 45 f0 48 8b 45 f0 48 8b 00 48 85 c0 74 09 48 8b 45 f0 48 8b 00 ff d0 48 83 45 f8 } //1
		$a_01_1 = {00 6f 75 74 2e 64 6c 6c 00 6d 61 69 6e 00 } //1 漀瑵搮汬洀楡n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}