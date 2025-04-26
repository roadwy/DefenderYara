
rule Trojan_MacOS_ProxyAgnt_K_MTB{
	meta:
		description = "Trojan:MacOS/ProxyAgnt.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {48 83 ec 27 48 83 e4 f0 48 89 44 24 10 48 89 5c 24 18 48 8d 3d 41 08 b1 00 48 8d 9c 24 68 00 ff ff 48 89 5f 10 48 89 5f 18 48 89 1f 48 89 67 08 b8 00 00 00 00 0f a2 89 c6 83 f8 00 74 33 81 fb 47 65 6e 75 75 1e 81 fa 69 6e 65 49 75 16 81 f9 6e 74 65 6c 75 0e c6 05 91 ec b3 00 01 c6 05 8e ec b3 00 01 } //1
		$a_00_1 = {45 73 74 61 62 6c 69 73 68 50 65 65 72 54 6f 50 72 6f 78 79 4d 67 72 52 65 71 75 65 73 74 } //1 EstablishPeerToProxyMgrRequest
		$a_00_2 = {2a 63 6e 63 2e 45 73 74 61 62 6c 69 73 68 50 65 65 72 54 6f 50 72 6f 78 79 4d 67 72 52 65 70 6c 79 } //1 *cnc.EstablishPeerToProxyMgrReply
		$a_00_3 = {70 72 6f 78 79 6d 61 6e 61 67 65 72 43 6f 6e 6e 65 63 74 69 6f 6e 44 75 72 61 74 69 6f 6e } //1 proxymanagerConnectionDuration
		$a_00_4 = {63 6e 63 4d 6f 64 65 6c 2e 41 74 74 61 63 68 52 65 70 6c 79 56 32 52 } //1 cncModel.AttachReplyV2R
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}