
rule Trojan_Win64_Midie_SXD_MTB{
	meta:
		description = "Trojan:Win64/Midie.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 04 10 48 8d 49 ?? 66 0f 6f ce 66 0f fc c8 f3 0f 7f 0c 10 f3 0f 6f 41 ?? 66 0f 6f ce 66 0f fc c6 f3 0f 7f 44 10 ?? f3 0f 6f 44 10 ?? 66 0f fc c8 f3 0f 7f 4c 10 ?? f3 0f 6f 44 10 ?? 66 0f 6f ce 66 0f fc c8 f3 0f 7f 4c 10 } //20
		$a_03_1 = {48 8d 55 c0 c7 45 c0 10 00 00 00 48 8b c8 48 8b d8 ff 15 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 48 8d 4d d8 ff 15 ?? ?? ?? ?? 4c 8d 4d d8 4c 8d 45 c8 48 8d 55 d0 48 8d 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4c 8d 4d d8 4c 8d 45 c8 48 8d 55 d0 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}